await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const id = document.querySelector("#incident-id").value.trim();
  check(id.length > 0, "Enter the fixture Guid");
  const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  check(response.status === 200, `Unexpected HTTP ${response.status}`);
  const data = await response.json();
  check(data.description.includes("data-lab05-marker"), "Wrong fixture");
  check(document.querySelector("#lab05-marker-target")
    .getAttribute("data-lab05-marker") === null, "Reload before test");
  await load();
  const box = document.querySelector("#description");
  check(box.textContent === data.description, "Text changed");
  check(box.childElementCount === 0, "Data became HTML elements");
  await new Promise(resolve => setTimeout(resolve, 500));
  check(document.querySelector("#lab05-marker-target")
    .getAttribute("data-lab05-marker") === null, "Marker executed");
  console.log("PASS: persisted description rendered as plain text");
})();
