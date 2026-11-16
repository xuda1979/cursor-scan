// XSS-safe patterns — must produce zero findings.
const banner = document.getElementById("banner");

function renderName(text) {
  banner.textContent = text;
}

function addRow(text) {
  const row = document.createElement("li");
  row.innerText = text;
  banner.appendChild(row);
}

function renderCard(title, body) {
  const card = document.createElement("article");
  card.innerText = title + " " + body;
  banner.appendChild(card);
}

function renderReact(name) {
  return React.createElement("h1", { title: name }, name);
}

function writeStatic() {
  document.write("<p>static footer</p>");
}
