document.addEventListener('DOMContentLoaded', () => {
    const nodes = document.querySelectorAll('[data-timestamp]');
    if (!nodes.length) {
        return;
    }

    const formatter = new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short'
    });

    nodes.forEach((node) => {
        const raw = node.getAttribute('data-timestamp');
        if (!raw) {
            return;
        }

        const date = new Date(raw);
        if (Number.isNaN(date.getTime())) {
            return;
        }

        node.textContent = formatter.format(date);
    });
});