(function () {
  var btn = document.getElementById("theme-toggle");
  function cur() { return document.documentElement.getAttribute("data-theme") || "dark"; }
  function label() { if (btn) btn.textContent = "[ " + (cur() === "dark" ? "light" : "dark") + " ]"; }
  label();
  if (btn) {
    btn.addEventListener("click", function () {
      var next = cur() === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) {}
      label();
    });
  }
})();
