function initAutocomplete(inputEl, suggestions) {
    if (!inputEl || inputEl.readOnly) return;

    var wrapper = document.createElement('div');
    wrapper.className = 'autocomplete-wrapper';
    inputEl.parentNode.insertBefore(wrapper, inputEl);
    wrapper.appendChild(inputEl);

    var list = document.createElement('ul');
    list.className = 'autocomplete-list';
    wrapper.appendChild(list);

    var activeIndex = -1;

    function escapeHtml(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderList(filter) {
        var val = filter.toLowerCase();
        var matches = val === ''
            ? suggestions.slice()
            : suggestions.filter(function(s) { return s.toLowerCase().includes(val); });

        list.innerHTML = '';
        activeIndex = -1;

        if (matches.length === 0) {
            list.style.display = 'none';
            return;
        }

        matches.forEach(function(suggestion) {
            var li = document.createElement('li');
            li.className = 'autocomplete-item';
            li.dataset.value = suggestion;

            if (val) {
                var lowerSug = suggestion.toLowerCase();
                var idx = lowerSug.indexOf(val);
                if (idx >= 0) {
                    li.innerHTML =
                        escapeHtml(suggestion.slice(0, idx)) +
                        '<span class="autocomplete-highlight">' +
                        escapeHtml(suggestion.slice(idx, idx + val.length)) +
                        '</span>' +
                        escapeHtml(suggestion.slice(idx + val.length));
                } else {
                    li.textContent = suggestion;
                }
            } else {
                li.textContent = suggestion;
            }

            li.addEventListener('mousedown', function(e) {
                e.preventDefault();
                inputEl.value = suggestion;
                list.style.display = 'none';
                activeIndex = -1;
            });

            list.appendChild(li);
        });

        list.style.display = 'block';
    }

    inputEl.addEventListener('input', function() {
        renderList(this.value);
    });

    inputEl.addEventListener('focus', function() {
        renderList(this.value);
    });

    inputEl.addEventListener('blur', function() {
        setTimeout(function() {
            list.style.display = 'none';
            activeIndex = -1;
        }, 150);
    });

    inputEl.addEventListener('keydown', function(e) {
        var items = list.querySelectorAll('.autocomplete-item');
        if (list.style.display === 'none' || items.length === 0) return;

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            activeIndex = Math.min(activeIndex + 1, items.length - 1);
            items.forEach(function(item, i) {
                item.classList.toggle('active', i === activeIndex);
            });
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            activeIndex = Math.max(activeIndex - 1, 0);
            items.forEach(function(item, i) {
                item.classList.toggle('active', i === activeIndex);
            });
        } else if (e.key === 'Enter' && activeIndex >= 0) {
            e.preventDefault();
            inputEl.value = items[activeIndex].dataset.value;
            list.style.display = 'none';
            activeIndex = -1;
        } else if (e.key === 'Escape') {
            list.style.display = 'none';
            activeIndex = -1;
        }
    });
}
