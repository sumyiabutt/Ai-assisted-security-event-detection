(function () {
  "use strict";

  const dropzone = document.querySelector("[data-dropzone]");
  if (dropzone) {
    const input = dropzone.querySelector('input[type="file"]');
    const label = dropzone.querySelector("[data-file-name]");

    const showName = () => {
      if (!input || !label) return;
      label.textContent = input.files && input.files.length ? input.files[0].name : "no file selected";
    };

    ["dragenter", "dragover"].forEach((type) => {
      dropzone.addEventListener(type, (event) => {
        event.preventDefault();
        dropzone.classList.add("is-dragover");
      });
    });

    ["dragleave", "drop"].forEach((type) => {
      dropzone.addEventListener(type, (event) => {
        event.preventDefault();
        dropzone.classList.remove("is-dragover");
      });
    });

    dropzone.addEventListener("drop", (event) => {
      if (!input) return;
      const files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) {
        input.files = files;
        showName();
      }
    });

    if (input) {
      input.addEventListener("change", showName);
    }
  }

  document.querySelectorAll("[data-auto-submit]").forEach((select) => {
    select.addEventListener("change", () => {
      if (select.form) select.form.submit();
    });
  });
})();
