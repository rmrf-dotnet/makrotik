/* ── Checkbox ── */
      function toggleCb(wrap) {
        wrap.querySelector(".checkbox").classList.toggle("is-checked");
      }

      /* ── Nav tabs ── */
      function switchNav(navId, btn) {
        document
          .querySelectorAll("#" + navId + " .nav-item")
          .forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
      }

      /* ── Dropdown ── */
      const ddState = {};
      function toggleDd(id) {
        const isOpen = ddState[id];
        Object.keys(ddState).forEach((k) => {
          ddState[k] = false;
          document.getElementById(k).classList.remove("is-open");
        });
        if (!isOpen) {
          ddState[id] = true;
          document.getElementById(id).classList.add("is-open");
        }
      }

      document.addEventListener("click", function (e) {
        if (!e.target.closest(".dropdown-wrap")) {
          Object.keys(ddState).forEach((k) => {
            ddState[k] = false;
            const el = document.getElementById(k);
            if (el) el.classList.remove("is-open");
          });
        }
      });

      /* ── Modal ── */
      function openModal() {
        document.getElementById("modal").classList.add("is-open");
      }

      function closeModal() {
        const m = document.getElementById("modal");
        m.style.opacity = "0";
        m.style.transform = "translateY(16px) scale(0.975)";
        m.style.transition =
          "opacity var(--duration-fast) var(--ease-exit), transform var(--duration-fast) var(--ease-exit)";
        setTimeout(function () {
          m.classList.remove("is-open");
          m.style.removeProperty("opacity");
          m.style.removeProperty("transform");
          m.style.removeProperty("transition");
        }, 140);
      }

      /* ── Easing balls ── */
      const balls = ["eb-enter", "eb-exit", "eb-standard", "eb-spring"];
      let forward = false;

      function animateBalls() {
        forward = !forward;
        balls.forEach(function (id) {
          const el = document.getElementById(id);
          const max = el.parentElement.offsetWidth - 11;
          el.style.left = forward ? max + "px" : "0px";
        });
      }

      /* Modal auto-open */
      setTimeout(function () {
        document.getElementById("modal").classList.add("is-open");
      }, 700);

      /* Start ball loop */
      setTimeout(function () {
        animateBalls();
        setInterval(animateBalls, 1500);
      }, 900);