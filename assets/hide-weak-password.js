/**
 * Hide the "Confirm use of weak password" opt-in on the user screens.
 *
 * UX only. Enforcement is server side in src/Modules/Passwords.php — removing
 * this checkbox changes nothing about what the server accepts.
 */
window.addEventListener('load', function () {
  if (!document.getElementById('createuser') && !document.getElementById('your-profile')) {
    return;
  }

  document.querySelectorAll('.pw-weak').forEach(function (el) {
    el.remove();
  });
});
