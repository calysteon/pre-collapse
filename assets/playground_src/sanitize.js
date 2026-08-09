function render(el, userText) {
  // writes caller-supplied text straight into the page
  el.innerHTML = '<span class="c">' + userText + '</span>';
}
module.exports = render;
