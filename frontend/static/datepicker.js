(function () {
    var MONTHS = ['January','February','March','April','May','June',
                  'July','August','September','October','November','December'];
    var DAYS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

    function toMidnight(d) {
        var n = new Date(d);
        n.setHours(0, 0, 0, 0);
        return n;
    }

    function toDateObj(val) {
        if (!val) return null;
        if (val instanceof Date) return toMidnight(val);
        if (typeof val === 'string') {
            var parts = val.split('-');
            return new Date(+parts[0], +parts[1] - 1, +parts[2]);
        }
        return null;
    }

    function pad(n) { return n < 10 ? '0' + n : '' + n; }

    function toISO(d) {
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    }

    window.initDatePicker = function (inputEl, opts) {
        opts = opts || {};
        var minDate = toDateObj(opts.minDate);
        var maxDate = toDateObj(opts.maxDate);

        inputEl.readOnly = true;
        inputEl.style.cursor = 'pointer';

        var wrapper = document.createElement('span');
        wrapper.className = 'dp-wrapper';
        inputEl.parentNode.insertBefore(wrapper, inputEl);
        wrapper.appendChild(inputEl);

        var icon = document.createElement('span');
        icon.className = 'dp-icon';
        icon.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle"><rect x="1" y="3" width="14" height="12" rx="1.5" stroke="#555" stroke-width="1.4"/><path d="M1 7h14" stroke="#555" stroke-width="1.4"/><path d="M5 1v4M11 1v4" stroke="#555" stroke-width="1.4" stroke-linecap="round"/></svg>';
        wrapper.appendChild(icon);

        var popup = document.createElement('div');
        popup.className = 'dp-popup';
        popup.style.display = 'none';
        wrapper.appendChild(popup);

        var viewYear, viewMonth;
        var selectedDate = null;

        function initView() {
            var base = selectedDate || minDate || new Date();
            viewYear = base.getFullYear();
            viewMonth = base.getMonth();
        }

        function render() {
            var today = toMidnight(new Date());
            var firstDay = new Date(viewYear, viewMonth, 1);
            var startDow = firstDay.getDay();
            var daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();

            var html = '<div class="dp-header">'
                + '<span class="dp-nav dp-prev">&#8249;</span>'
                + '<span class="dp-month-year">' + MONTHS[viewMonth] + ' ' + viewYear + '</span>'
                + '<span class="dp-nav dp-next">&#8250;</span>'
                + '</div><div class="dp-grid">';

            DAYS.forEach(function (d) {
                html += '<span class="dp-dow">' + d + '</span>';
            });

            for (var i = 0; i < startDow; i++) {
                html += '<span class="dp-day dp-empty"></span>';
            }

            for (var day = 1; day <= daysInMonth; day++) {
                var d = new Date(viewYear, viewMonth, day);
                var cls = 'dp-day';
                var disabled = false;

                if (minDate && d < minDate) { cls += ' dp-disabled'; disabled = true; }
                if (maxDate && d > maxDate) { cls += ' dp-disabled'; disabled = true; }
                if (d.getTime() === today.getTime()) cls += ' dp-today';
                if (selectedDate && d.getTime() === selectedDate.getTime()) cls += ' dp-selected';

                html += '<span class="' + cls + '"'
                    + (disabled ? '' : ' data-date="' + toISO(d) + '"')
                    + '>' + day + '</span>';
            }

            html += '</div>';
            popup.innerHTML = html;

            popup.querySelector('.dp-prev').addEventListener('click', function (e) {
                e.stopPropagation();
                viewMonth--;
                if (viewMonth < 0) { viewMonth = 11; viewYear--; }
                render();
            });
            popup.querySelector('.dp-next').addEventListener('click', function (e) {
                e.stopPropagation();
                viewMonth++;
                if (viewMonth > 11) { viewMonth = 0; viewYear++; }
                render();
            });

            popup.querySelectorAll('.dp-day[data-date]').forEach(function (cell) {
                cell.addEventListener('click', function (e) {
                    e.stopPropagation();
                    var iso = cell.getAttribute('data-date');
                    inputEl.value = iso;
                    selectedDate = toDateObj(iso);
                    inputEl.dispatchEvent(new Event('input', { bubbles: true }));
                    inputEl.dispatchEvent(new Event('change', { bubbles: true }));
                    close();
                });
            });
        }

        function open() {
            if (!viewYear) initView();
            render();
            popup.style.display = 'block';

            // Overflow guard: flip left if off right edge
            var rect = popup.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                popup.style.left = 'auto';
                popup.style.right = '0';
            } else {
                popup.style.left = '0';
                popup.style.right = 'auto';
            }
        }

        function close() {
            popup.style.display = 'none';
        }

        function toggle(e) {
            e.stopPropagation();
            if (popup.style.display === 'none') {
                open();
            } else {
                close();
            }
        }

        inputEl.addEventListener('click', toggle);
        icon.addEventListener('click', toggle);

        document.addEventListener('click', function (e) {
            if (!wrapper.contains(e.target)) close();
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') close();
        });

        popup.addEventListener('click', function (e) { e.stopPropagation(); });
    };
}());
