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

function loadUserScript(url) {
  const script = document.createElement("script");
  script.src = url;
  document.head.appendChild(script);
}

function embedUserPage(url) {
  const frame = document.createElement("iframe");
  frame.src = url;
  document.body.appendChild(frame);
}

function renderSnippet(snippet) {
  const button = document.querySelector("#run");
  button.setAttribute("onclick", snippet);
}

function insertBanner(html) {
  $("#banner").append(html);
}

function prependMenu(html) {
  $("#menu").prepend(html);
}

function replaceRow(html) {
  jQuery("#rows .row").replaceWith(html);
}

function wrapWithCard(html) {
  $("article").wrap(`<div class="card">${html}</div>`);
}

function loadPlugin(name) {
  $.getScript(url_for_plugin(name));
}

function loadExtra(version) {
  jQuery.getScript("https://cdn.example.com/lib-" + version + ".js");
}

function loadKnownPlugin() {
  $.getScript("https://cdn.example.com/plugin.js");
}

function replaceBanner(html) {
  document.getElementById("banner").outerHTML = html;
}

function updateCard(html) {
  queryCard().innerHTML = html;
}

function insertRow(html) {
  document.querySelector("#rows").insertAdjacentHTML("beforeend", html);
}
