// Deliberately unsafe DOM XSS patterns.
const banner = document.getElementById("banner");

function renderName(text) {
  banner.innerHTML = text;
}

function renderCard(html) {
  banner.outerHTML = html;
}

function addRow(html) {
  banner.insertAdjacentHTML("beforeend", html);
}

function legacyRender(value) {
  document.write(value);
}

function reactRender(userHtml) {
  const props = { dangerouslySetInnerHTML: { __html: userHtml } };
  return props;
}
