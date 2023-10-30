'use strict';

import multer from 'multer';
import http from 'http';
import https from 'https';
import express from 'express';
import crypto from 'node:crypto'
import tss from 'tss.js'
import fs from 'node:fs'
import * as llm from './llm.js'

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { exit } from 'process';

// HTTPS Configuration - set to null for HTTP
// const tls = null
const tls = {
  key: fs.readFileSync("/etc/ssl/privkey.pem"),
  cert: fs.readFileSync("/etc/ssl/cert.pem"),
  ca: fs.readFileSync("/etc/ssl/chain.pem")
}

// Port for the service
const port = tls ? 443 : 80;

// -----------------------------------------------------------------------

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

// HPKE Cipher suite
const suite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

// A recipient generates a key pair.
const rkp = await suite.kem.generateKeyPair();

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

const app = express()
const upload = multer({ dest: "uploads/" });

app.use("/upload", upload.array("files"), function(req, res, next){
  var ok = true;
  req.files.forEach(function(file){
    ok &= llm.loadFile("user0", file);
  })
  if(ok) res.writeHead(200, "OK");
  else res.writeHead(500, "Failed")
  res.end();
});

app.use("/kex", async (req, res, next) => {
  res.writeHead(200, "OK", ["Content-Type", "application/json"]);
  let jwk = JSON.stringify(await crypto.subtle.exportKey("jwk", rkp.publicKey));
  res.write(jwk);
  res.end();
});

app.use("/attest", function(req, res, next){
  res.writeHead(200, "OK", ["Content-Type", "application/x-hcl-attestation"]);
  res.write(hcl_report);
  res.end();
});

app.use("/query-stream", function(req, res, next) {
  console.log("Decrypting request: "+req.query.q);
  const query = JSON.parse(decrypt(req.query.q));
  res._plainWrite = res.write;

  // Add transparent encryption to stream fragments
  res.write = function(x, enc){
    return res._plainWrite(encrypt(x)+"\n\n", enc);
  }

  // Pass request to application
  try {
    llm.stream("user0", query, res);
  } catch(e) {
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

/*
var server = http.createServer((req, res) => {
  res.setHeader('Trailer', 'X-Attested-Signature');
  prox.web(req, res, {
    target: 'http://127.0.0.1:9000'
  });
});

server.listen(8000);

http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write('request successfully proxied!' + '\n' + JSON.stringify(req.headers, true, 2));
    res.end();
}).listen(9000);
*/
