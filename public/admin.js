document.addEventListener('submit', function (e) {
  var form = e.target;
  if (form.action.indexOf('/admin/') === -1) return;
  var msg = '';
  if (/\/delete\/\d+$/.test(form.action)) msg = 'Delete this user permanently?';
  else if (/\/ban\/\d+$/.test(form.action)) msg = 'Ban this user?';
  else if (/\/unban\/\d+$/.test(form.action)) msg = 'Unban this user?';
  else if (/\/remove-referral\/\d+$/.test(form.action)) msg = 'Remove referral badge?';
  else if (/\/make-admin\/\d+$/.test(form.action)) msg = 'Promote this user to admin?';
  else if (/\/rooms\/\d+\/delete$/.test(form.action)) msg = 'Delete this room permanently?';
  else if (/\/reports\/\d+\/ban$/.test(form.action)) msg = 'Ban the author of this message?';
  else if (/\/reports\/\d+\/delete$/.test(form.action)) msg = 'Remove the reported content?';
  else if (/\/reports\/\d+\/dismiss$/.test(form.action)) msg = 'Dismiss this report?';
  else if (/\/security-reports\/\d+\/handle$/.test(form.action)) msg = 'Mark this security report as handled?';
  if (msg && !confirm(msg)) e.preventDefault();
});
