document.addEventListener("DOMContentLoaded", () => {
  if (
    window.parent &&
    window.parent.document.body.classList.contains("bright-body")
  ) {
    document.body.classList.add("bright-body");
  }
});
