try {
  const t = localStorage.getItem("mm-theme");
  if (t) document.documentElement.dataset.theme = t;
} catch (e) {}
