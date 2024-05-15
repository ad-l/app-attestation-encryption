'use strict';

import multer from 'multer';
import http from 'http';
import https from 'https';
import express from 'express';
import crypto from 'node:crypto'
//import pem from 'pemtools'
import tss from 'tss.js'
import fs from 'node:fs'
import util from 'util';
import * as llm from './llm.js'

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { exit } from 'process';
import { exec } from 'child_process'

// The domain name to use for the service
const domain = "ragdemo.eastus2.cloudapp.azure.com";

// HTTPS Configuration - set to null for HTTP
// const tls = null
const tls = {
  key: fs.readFileSync(`/etc/letsencrypt/live/${domain}/privkey.pem`),
  cert: fs.readFileSync(`/etc/letsencrypt/live/${domain}/cert.pem`),
  ca: fs.readFileSync(`/etc/letsencrypt/live/${domain}/chain.pem`)
}

// Port for the service
const port = tls ? 443 : 80;

// AMD KDS and MAA endpoints
const IMDS = "http://169.254.169.254"
//const AMD_KDS = "https://kdsintf.amd.com";
const MAA = "https://sharedeus2.eus2.attest.azure.net"

// -----------------------------------------------------------------------

async function ecdh(privateKey, publicKey) {
  const sharedSecret = await crypto.subtle.deriveBits({name: "ECDH", namedCurve: "P-384", public: publicKey}, privateKey, 256);
}

var algorithm = 'aes-256-cbc';
function encrypt(text) {
    var cipher = crypto.createCipheriv(algorithm, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    try {
        var crypted = cipher.update(text, 'utf8', 'hex');
        crypted += cipher.final('hex');
    } catch (e) {
        return;
    }
    return crypted;
}

function decrypt(text) {
  var decipher = crypto.createDecipheriv(algorithm, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    try {
        var dec = decipher.update(text, 'hex', 'utf8');
        dec += decipher.final('utf8');
    } catch (e) {
      console.dir(e)
        return;
    }
    return dec;
}

// A recipient generates a key pair.
const rkp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384"}, false, ["deriveBits"]);
const jwk = JSON.stringify(await crypto.subtle.exportKey("jwk", rkp.publicKey));

/* Get Ek from TPM, and HCL attestation of Ek with NV_Read */
const EK_PersHandle = new tss.TPM_HANDLE(0x81000003);
const HCL_NV = new tss.TPM_HANDLE(0x1400001);
const OWNER = new tss.TPM_HANDLE(0x40000001);

const EK_template = new tss.TPMT_PUBLIC(tss.TPM_ALG_ID.SHA256,
    tss.TPMA_OBJECT.restricted | tss.TPMA_OBJECT.decrypt | tss.TPMA_OBJECT.fixedTPM | tss.TPMA_OBJECT.fixedParent
        | tss.TPMA_OBJECT.adminWithPolicy | tss.TPMA_OBJECT.sensitiveDataOrigin,
    null,
    new tss.TPMS_RSA_PARMS(tss.Aes128SymDef, new tss.TPMS_NULL_ASYM_SCHEME(), 2048, 0),
    new tss.TPM2B_PUBLIC_KEY_RSA());

const EK_info = {name: "EK", hierarchy: tss.Endorsement, handle: EK_PersHandle, template: EK_template, pub: null}
let ekpub = null, hcl_report = null;

function getTpmAttest()
{
    tpm.ReadPublic(EK_info.handle, (err, resp) => {
        if(err){ console.log('Error: '+err); hcl_report = 0; return };
        console.log('ReadPublic(' + EK_info.name + ') returned ' + tss.TPM_RC[tpm.lastResponseCode]);
        ekpub = resp.outPublic.unique.buffer.toString('hex');
        console.log('TPM endorsement public key: ' + ekpub);

        tpm.NV_ReadPublic(HCL_NV, (err, res) => {
            if(err){ console.log('Error: '+err); hcl_report = 0; return };
            console.log('HCL attestation metadata: size=' + res.nvPublic.dataSize + ', name=' + res.nvName.toString('hex'));
            HCL_NV.name = res.nvName;
            
            tpm.NV_Read(OWNER, HCL_NV, 1024, 0, (err, hcl1) => {
                if(err){ console.log('Error: '+err); hcl_report = 0; return };
                tpm.NV_Read(OWNER, HCL_NV, 1024, 1024, (err, hcl2) => {
                  if(err){ console.log('Error: '+err); hcl_report = 0; return };
                  tpm.NV_Read(OWNER, HCL_NV, res.nvPublic.dataSize-2048, 2048, (err, hcl3) => {
                    if(err){ console.log('Error: '+err); hcl_report = 0; return };
                    hcl_report = Buffer.concat([hcl1, hcl2, hcl3]);
                  });
                });
            })
        })
    });
}

let tpm = new tss.Tpm(false);
tpm.connect(getTpmAttest);

// Async use is dodgy in TSS (continuation passing) so we have to manually synchronize
// to avoid giant continuation
const timer = ms => new Promise( res => setTimeout(res, ms))
while(hcl_report === null) { await timer(100); }
if(!hcl_report) {
  console.err("TPM failure");
  exit(1);
}

// Extract SNP report and user data from HCL attestation
let snp = hcl_report.slice(32, 32+1184).toString("base64url");
let s0 = hcl_report[0x4d0], s1 = hcl_report[0x4d1];
let hwid = hcl_report.slice(448, 64+448);
let snp_data = hcl_report.slice(0x4d4, 0x4d4+(256*s1+s0)).toString("base64url");

// VCEK chain (cache on disk to avoid rate limit on AMD KDS)
var vcek = null, vcek_leaf = null;
if (fs.existsSync('vcek.pem')) {
  const { readFile } = await import("node:fs/promises");
  vcek = await readFile("vcek.pem");
}else{
  console.log("Refreshing the VCEK certificate chain from AMD KDS...")
  let vcek = await fetch(IMDS+"/metadata/THIM/amd/certification", {method:"GET", headers:{"Metadata":"true"}});
  vcek = await vcek.json();
  vcek = vcek.vcekCert + vcek.certificateChain;

/**
 * Alternative code to download from AMD KDS instead of IMDS
  // This is PEM encoded
  let kds = await fetch(AMD_KDS+"/vcek/v1/Genoa/cert_chain", {method:"GET"});
  let vcek_ca = Buffer.from(await (await kds.blob()).arrayBuffer());

  // This is DER...
  kds = await fetch(AMD_KDS+"/vcek/v1/Genoa/"+hwid.toString('hex')+"?ucodeSPL=22&snpSPL=11&teeSPL=0&blSPL=7", {method:"GET"});
  let cpucert = Buffer.from(await (await kds.blob()).arrayBuffer());

  // Combine them in a full chain
  vcek = Buffer.concat([Buffer.from(pem(cpucert, 'CERTIFICATE').toString()+"\n", "utf8"), vcek_ca]);
**/

  // Cache the chain to disk
  const { writeFile } = await import("node:fs/promises");
  await writeFile("vcek.pem", vcek);
}

const app = express()
const upload = multer({ dest: "uploads/" });

app.use("/upload", upload.array("files"), function(req, res, next){
  var ok = true;
  req.files.forEach(function(file){
    ok &= llm.loadFile(req.query.uid ?? "default", file);
  });
  if(ok) res.writeHead(200, "OK");
  else res.writeHead(500, "Failed")
  res.end();
});

let jwt = {cpu:null, gpu:null, jwk: jwk, time:0}
app.use("/attest", async function(req, res, next){
  res.writeHead(200, "OK", ["Content-Type", "application/json"]);

  // MAA token is expired
  if(!jwt.cpu || !jwt.gpu || jwt.time + 1000*60*20 > Date.now()){
    try {
      let nonce = Math.random();
      let vcek_url = vcek.toString("base64url");
      let snp_encoded = Buffer.from(`{"SnpReport":"${snp}", "VcekCertChain":"${vcek_url}"}`,"utf8").toString("base64url");
      const rbody = `{"report": "${snp_encoded}", "runtimeData":{"data":"${snp_data}", "dataType":"JSON"}, "nonce":"${nonce}"}\n`;

      // Ask MAA for an attestation token
      const maa = await fetch(MAA+"/attest/SevSnpVm?api-version=2022-08-01", {
        method: 'POST', body: rbody, mode: "cors", headers: {"Content-Type": "application/json"},
      });
      
      const token = await maa.json();
      jwt.cpu = token.token;

      const aexec = util.promisify(exec);
      let res = await aexec("gpuattest");
      jwt.gpu = res.stdout.split("\n")[4].substring(28);
      jwt.time = Date.now();
    }
    catch(e){
      console.log("Failed to refresh MAA token: "+e)
    }
  }

  res.write(JSON.stringify(jwt));
  res.end();
});

app.use("/query-stream", function(req, res, next) {
  console.log("Decrypting request: "+req.query.q+" for user "+req.query.uid);
  const query = JSON.parse(decrypt(req.query.q));
  res._plainWrite = res.write;

  // Add transparent encryption to stream fragments
  res.write = function(x, enc){
    return res._plainWrite(encrypt(x)+"\n\n", enc);
  }

  // Pass request to application
  try {
    llm.stream(req.query.uid, query, res);
  } catch(e) {
    console.log("Import error: "+e)
    res.writeHead(500, "Server error");
    res.end();
  }
});

// Serve files from the "static/" folder
app.use(express.static('static'));

if(tls) {
  console.log("Listening on https://0.0.0.0:"+port);
  https.createServer(tls, app).listen(port);
} else {
  console.log("Listening on http://0.0.0.0:"+port);
  app.listen(port);
}
