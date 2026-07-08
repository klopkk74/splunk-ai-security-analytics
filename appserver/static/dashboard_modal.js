require([
    'jquery',
    'splunkjs/mvc/simplexml/ready!'
], function($) {
    // 1. Nhúng khung giao diện Modal
    if ($('#ai-custom-modal').length === 0) {
        $('body').append(`
            <div id="ai-custom-modal" style="display:none; position:fixed; z-index:9999; left:0; top:0; width:100%; height:100%; background-color:rgba(0,0,0,0.85); backdrop-filter: blur(4px);">
                <div style="background-color:#141b24; margin: 4% auto; padding: 25px; border: 1px solid #222b38; border-radius: 8px; width: 75%; max-height: 85vh; overflow-y: auto; box-shadow: 0 0 20px rgba(0,0,0,0.5);">
                    <span id="ai-close-modal" style="color:#9ca3af; float:right; font-size:28px; font-weight:bold; cursor:pointer; line-height: 20px;">&times;</span>
                    <h2 id="ai-modal-title" style="color: #60a5fa; margin-top: 0; padding-bottom: 15px; border-bottom: 1px solid #222b38; font-family: -apple-system, sans-serif; text-transform: uppercase;">Tiêu đề</h2>
                    <div id="ai-modal-content" style="color:#d1d5db; font-family:'Consolas', monospace; white-space: pre-wrap; line-height: 1.7; font-size: 14px; margin-top: 15px;"></div>
                </div>
            </div>
        `);
    }

    // 2. Lắng nghe sự kiện click (ĐÃ SỬA LỖI LẤY DỮ LIỆU)
    // Thay vì tìm thẻ ẩn, JS sẽ quét trực tiếp phần chữ trong thẻ "text-fade-container" ngay phía trên nút bấm
    $(document).on('click', '.view-details-btn', function(e) {
        e.preventDefault();
        var title = $(this).data('title');
        
        // Lấy dữ liệu thực tế đang hiển thị trên màn hình
        var fullContent = $(this).siblings('.text-fade-container').html();

        $('#ai-modal-title').text(title);
        $('#ai-modal-content').html(fullContent);
        $('#ai-custom-modal').fadeIn(200);
    });

    // 3. Đóng Modal
    $(document).on('click', '#ai-close-modal', function() {
        $('#ai-custom-modal').fadeOut(200);
    });
    $(window).on('click', function(e) {
        if (e.target.id === 'ai-custom-modal') {
            $('#ai-custom-modal').fadeOut(200);
        }
    });
});
