// Form validation for signup
document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', function(e) {
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const role = document.getElementById('role').value;

            if (username.length < 3) {
                e.preventDefault();
                alert('Username must be at least 3 characters long');
                return;
            }

            // Password complexity validation
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
            if (!passwordRegex.test(password)) {
                e.preventDefault();
                alert('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character');
                return;
            }

            if (!email.includes('@')) {
                e.preventDefault();
                alert('Please enter a valid email address');
                return;
            }

            if (!role) {
                e.preventDefault();
                alert('Please select a role');
                return;
            }
        });
    }

    // Form validation for login
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            if (!username || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
                return;
            }
        });
    }

    // Form validation for password reset
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            // Password complexity validation
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
            if (!passwordRegex.test(password)) {
                e.preventDefault();
                alert('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character');
                return;
            }

            if (password !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match');
                return;
            }
        });
    }

    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.opacity = '0';
            setTimeout(function() {
                message.remove();
            }, 500);
        }, 5000);
    });
}); 