function update_hidden_filter_radiobuttons() {
    document.querySelectorAll('input[type="radio"]').forEach(radio => {
        let label = document.querySelector('label[for="' + radio.id + '"]');
        if (radio.checked) {
            label.classList.remove("btn-outline-secondary");
            label.classList.add("btn-primary");
        } else {
            label.classList.remove("btn-primary");
            label.classList.add("btn-outline-secondary");
        }
    })
}