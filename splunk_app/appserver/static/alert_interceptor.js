require([
    "jquery",
    "splunkjs/mvc/simplexml/ready!"
], function($) {
    
    console.log("Gemini SOC: Trình chặn Alert Interceptor đã khởi động thành công!");

    // Đổi 'a' thành 'td' để bắt click vào ô bảng chứa chữ Analysis alert
    $(document).on("click", "td:contains('Analysis alert')", function(e) {
        
        e.preventDefault(); 
        e.stopPropagation();

        // Đi ngược lên lấy toàn bộ dòng (tr) chứa ô vừa click
        var $currentRow = $(this).closest("tr");
        
        // Trong bảng hiển thị, sid nằm ở cột thứ 4
        var sid = $currentRow.find("td:nth-child(4)").text().trim();

        if (!sid || sid === "") {
            alert("Lỗi: Không tìm thấy Search ID (SID) của Alert này!");
            return;
        }

        // Sinh Form thu thập thời gian
        var timeWindow = prompt("Nhập số phút quét mở rộng (Ví dụ: 5 phút trước và sau sự cố):", "5");

        if (timeWindow !== null && timeWindow.trim() !== "") {
            // Hiệu ứng loading cho user đỡ sốt ruột
            $(this).text("Đang điều hướng...").css("color", "red");

            // Điều hướng
            var targetDashboardUrl = "incident_investigation_dashboard";
            var queryParams = "?form.sid=" + encodeURIComponent(sid) + "&form.time=" + encodeURIComponent(timeWindow.trim());
            window.location.href = targetDashboardUrl + queryParams;
        }
    });

    // Cải thiện UI: Đổi con trỏ chuột thành hình bàn tay khi hover qua cột Action
    $(document).on("mouseenter", "td:contains('Analysis alert')", function() {
        $(this).css("cursor", "pointer").css("font-weight", "bold").css("color", "#1e62b5");
    }).on("mouseleave", "td:contains('Analysis alert')", function() {
        $(this).css("font-weight", "normal").css("color", "");
    });
});
