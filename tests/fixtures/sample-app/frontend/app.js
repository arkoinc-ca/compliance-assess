// Sample dashboard frontend.
import axios from "axios";

async function login(user) {
  // VIOLATION: pii-in-logs-javascript — console.$LEVEL($X.email) and console.$LEVEL($X.password)
  console.log(user.email);
  console.error(user.password);

  // VIOLATION: missing-consent-javascript — sendEmail($USER, ...) without consent guard
  sendEmail(user, "Welcome!", "Buy our stuff");
}

function sendEmail(user, subject, body) {
  return axios.post("/api/email", { to: user.email, subject, body });
}
