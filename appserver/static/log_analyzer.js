require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    
    function getUrlParams() {
        var params = {};
        var searchParams = new URLSearchParams(window.location.search);
        for (var key of searchParams.keys()) {
            params[key] = searchParams.get(key);
        }
        return params;
    }

    var params = getUrlParams();
    
    if (Object.keys(params).length === 0) {
        $("#ai_status").text("No log data provided.");
        return;
    }

    function getCsrfToken() {
        var match = document.cookie.match(new RegExp('(^| )splunkweb_csrf_token_8000=([^;]+)'));
        if (match) return match[2];
        match = document.cookie.match(new RegExp('(^| )splunkweb_csrf_token=([^;]+)'));
        if (match) return match[2];
        return "";
    }

    var locale = window.location.pathname.split('/')[1] || 'en-US';
    var restUrl = "/" + locale + "/splunkd/__raw/services/gemini_ai/analyze_log";

    $.ajax({
        url: restUrl,
        type: 'GET',
        data: params,
        dataType: 'json',
        timeout: 180000, 
        headers: { 'X-Splunk-Form-Key': getCsrfToken() },
        success: function(response) {
            $("#ai_status").hide();
            $("#ai_result").show();
            
            var data = response;
            if (response.payload) {
                if (typeof response.payload === 'string') {
                    try { data = JSON.parse(response.payload); } catch(e) { console.error("JSON parse error", e); }
                } else {
                    data = response.payload;
                }
            }
            
            $("#cell_prompt").text(data.prompt || "No prompt data");
            
            var rawReply = data.ollama_reply || "No response received from AI.";
            var escapedReply = $('<div>').text(rawReply).html();
            var formattedReply = escapedReply.replace(/\n/g, "<br>");
            
            $("#cell_reply").html(formattedReply);
        },
        error: function(xhr, status, error) {
            var errorMsg = xhr.responseText || error;
            if (status === "timeout") {
                // Thong bao loi chuyen nghiep khi demo that bai do qua tai
                errorMsg = "AI processing timeout. He thong dang qua tai, vui long thu lai.";
            }
            $("#ai_status").css("color", "red").text("System Alert: " + errorMsg);
        }
    });
});
