// Main JavaScript for VXDF Validate
document.addEventListener('DOMContentLoaded', function() {
    console.log('VXDF Validate loaded');
    
    // Flash message handling
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.classList.add('fade-out');
            setTimeout(() => {
                message.remove();
            }, 500);
        }, 3000);
    });
});
