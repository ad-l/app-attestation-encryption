/*
Sample retrival augmented chat application.
This is based off https://js.langchain.com/docs/modules/chains/popular/chat_vector_db
Distributed under MIT license.
*/

import { PDFLoader } from "langchain/document_loaders/fs/pdf";
import { Document } from "langchain/document";
import { ChatOllama } from "langchain/chat_models/ollama";
import { OllamaEmbeddings } from "langchain/embeddings/ollama";;
import { LLMChain } from "langchain/chains";
import { HNSWLib } from "langchain/vectorstores/hnswlib";
import { RecursiveCharacterTextSplitter } from "langchain/text_splitter";
import { BufferMemory } from "langchain/memory";
import * as fs from "fs";
import { PromptTemplate } from "langchain/prompts";
import { RunnableSequence } from "langchain/schema/runnable";
import { BaseMessage } from "langchain/schema";
import { formatDocumentsAsString } from "langchain/util/document";
import { StringOutputParser } from "langchain/schema/output_parser";

/**** Application configuration ****/
let OLLAMA_URL = "http://127.0.0.1:11434";
let OLLAMA_MODEL = "llama2"

// Delete cached documents after user is inactive for x ms
let USER_TIMEOUT = 10 * 60 * 60 * 1000;

/***********************************/

// We create an in-memory HNSW store for each user
// The data is only stored for a limited time, and
// can only be queried by the owner
let users = {};

// Ollama configuration
const ollama = new ChatOllama({
    baseUrl: OLLAMA_URL,
    model: OLLAMA_MODEL,
});

// Force model to load and stay in GPU memory
console.log("Loading model...")
async function ping(){ try{ollama.invoke("Hi");} catch(e){} }
setInterval(ping, 4*60*1000);
let _ = await ping();
console.log("Model loaded.");

// Classes to import text and PDF documents
const pdf = new PDFLoader();
const txt = new RecursiveCharacterTextSplitter({ chunkSize: 500, chunkOverlap: 20 });

// Keep chat history in user object
function formatHistory(human, ai, previous)
{
    const newInteraction = `Human: ${human}\nAI: ${ai}`;
    if (!previous) {
      return newInteraction;
    }
    return `${previous}\n\n${newInteraction}`;
}

const questionPrompt = PromptTemplate.fromTemplate(
    `Use the following pieces of context to answer the question at the end. If you don't know the answer, just say that you don't know, don't try to make up an answer.
    ----------------
    CONTEXT: {context}
    ----------------
    CHAT HISTORY: {chatHistory}
    ----------------
    QUESTION: {question}
    ----------------
    Helpful Answer:`
);

const chain = RunnableSequence.from([
    {
      question: (input) => input.question,
      chatHistory: (input) => input.chatHistory ?? "",
      context: (input) => input.context ?? "",
    },
    questionPrompt,
    ollama,
    new StringOutputParser(),
  ]);

async function checkUser(uid){
    const clearUser = () => {delete users[uid]};
    if(users[uid])
    {
        clearTimeout(users[uid].timer);
        users[uid].timer = setTimeout(clearUser, USER_TIMEOUT);
    } else {
        const docs = [new Document({pageContent:"The current date is "+(new Date()), matadata: { name: "<inference app>" }})];
        const vec = await HNSWLib.fromDocuments(docs, new OllamaEmbeddings());

        users[uid] = {
            retriever: vec.asRetriever(),
            docs: docs,
            history: "",
            timer: setTimeout(clearUser, USER_TIMEOUT)
        }
    }
    return users[uid];
}

// Prompt handler
// - user is the unique user ID
// - in is the input object
// - res is the writable response stream
export async function stream(uid, q, res){
    const user = await checkUser(uid);

    console.log("Prompt "+q.text);
    const relevantDocs = q.rag == "true" ?
        await user.retriever.getRelevantDocuments(q.text) : [];
    console.log("Found "+relevantDocs.length+" relevant documents");

    const stream = chain.stream({
        uid: uid,
        context: formatDocumentsAsString(relevantDocs),
        question: q.text,
        chatHistory: user.history
    }).then(async stream => {
        var ai = "";
        res.writeHead(200, res.rawHeaders);
        for await (const chunk of stream) {
            res.write(chunk);
            ai += chunk;
        }
        user.history = formatHistory(q.text, ai, user.history);

        // Write context information
        var extra = "", n = "";
        relevantDocs.forEach(function(x){
          if(x.metadata.name) {
            if(n != x.metadata.name) {
                n = x.metadata.name;
                extra += (extra?", ":"")+"File `"+n+"`";
            }
            if(x.metadata.loc && x.metadata.loc.pageNumber)
                  extra += ", page "+x.metadata.loc.pageNumber;
          }
        });

        if(extra){
            extra = "\n\nSee also: "+extra;
            res.write(extra);
        }

        res.end();
    })
    .catch(err => {
        console.dir(err);
        res.writeHead(500, "Internal Error");
        res.write(err);
        res.end();
    });
}

// Load the file in the user's vector database
// Supports PDF and TXT files
export async function loadFile(uid, file) {
    const user = await checkUser(uid);
    const fn = file.originalname;
    const ext = fn.split('.').pop().toLowerCase();
    console.log("Importing "+fn+" for user "+uid)

    try {
        var docs = [];
        if(ext == "pdf") {
            const { readFile } = await import("node:fs/promises");
            const buffer = await readFile(file.path);
            docs = await pdf.parse(buffer, {name: fn});
        } else if (ext == "txt") {
            const text = fs.readFileSync(file.path, "utf8");
            const docs = await txt.createDocuments([text], { name: fn });
        }
        console.log("Extracted "+docs.length+" chunks from "+fn);
        user.docs.push.apply(user.docs, docs);
        const vec = await HNSWLib.fromDocuments(docs, new OllamaEmbeddings());
        user.retriever = vec.asRetriever();
        return true;
    } catch(e) {
        console.log(e);
        return false;
    } finally {
        // Delete the file
        fs.unlink(file.path, (err) => {});
    }
}
