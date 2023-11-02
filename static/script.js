const controller = new AbortController();

if (document.cookie.indexOf('__attestation_extension__') == -1) {
  $("#extwarn").show();
} else {
  window.postMessage("__attestation_init", self.origin);
}

var uid;
function refreshUser(){uid = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');}
refreshUser();

async function query(prompt, rag)
{
  const q = encrypt(JSON.stringify({text:prompt, rag:rag}));
  const response = await fetch("/query-stream?uid="+uid+"&q="+encodeURIComponent(q), {
    method: "GET",
    mode: "cors",
    cache: "no-cache",
    signal: controller.signal
  });
  let reader = response.body.getReader();
  const decoder = new TextDecoder();
  var converter = new showdown.Converter();

  var answer = "";
  var ahtml = $(`<div class="max-w-[80%] min-w-[40%] rounded-lg p-4 mb-4 overflow-x-auto bg-white border border-indigo-200 s-XsEmFtvddWTw"></div>`);
  var aimg = $('<img src="loading.gif" alt="(response in progress)" />')
  var ap = $("<p></p>");

  ahtml.append(aimg);
  ahtml.append(ap);
  $("#msgs").append(ahtml);
  $("#scroll").animate({ scrollTop: $('#scroll').prop("scrollHeight")}, 100);

  reader.read().then(function processText({ done, value }) {
    value = decoder.decode(value).split("\n\n");
    value.forEach(function(str){
      answer += decrypt(str);
//      if(str.startsWith("data: ")){
//        var j = JSON.parse(str.substr(6));
//        if(j.token){
//          answer += j.token;
//        }
//      }
    });

    ap.html(converter.makeHtml(answer))
    $("#scroll").scrollTop($('#scroll').prop("scrollHeight"));

    if (done) {
        ahtml.empty(); ahtml.append(ap);
        $("#scroll").animate({ scrollTop: $('#scroll').prop("scrollHeight")}, 100);
        $('#prompt').prop('disabled', false);
        return;
    }
    return reader.read().then(processText);
  }).catch(err => {
    alert(err);
    ahtml.empty(); ahtml.append(ap);
    $('#prompt').prop('disabled', false);
  });
}

$("form#ragfile").on("submit", function(e){
    e.preventDefault();
    const files = document.getElementById("files");
    const formData = new FormData();
    for(let i =0; i < files.files.length; i++) {
        formData.append("files", files.files[i]);
    }
    fetch("/upload?uid="+uid, {
        method: 'POST',
        body: formData,
    }).then((res) => alert("Your data has been added to the RAG database!"))
    .catch((err) => {alert("Error processing PDF"); });
})

$("form#chat").on("submit", function(){
//    if(!window.sk) return false;
    var prompt = $("input#prompt").val();
    var rag = $("input[name=rag]:checked").val();
    $('#prompt').prop('disabled', true);
    $("#msgs").append($(`<div class="max-w-[80%] min-w-[40%] rounded-lg p-4 mb-4 overflow-x-auto bg-white border border-indigo-200 s-XsEmFtvddWTw self-end text-right"><p>${prompt}</p></div>`));
    $("#scroll").animate({ scrollTop: $('#scroll').prop("scrollHeight")}, 100);
    query(prompt, rag);
    return false;
})

$("#abort").on("click", () => {controller.abort();$('#prompt').prop('disabled', false);})
$("#clear").on("click", () => {$("#msgs").empty(); refreshUser();})

function encrypt(p){
    aes.setKey("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    return encoding.astr2hstr(aes.CBC(encoding.utf8_decode(p), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 0));
}

function decrypt(p){
    aes.setKey("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    return encoding.utf8_encode(aes.CBC(encoding.hstr2astr(p), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 1));
}