function makeEditable(button) {
    let form = button.parentNode;
    form.querySelectorAll("[data-input]").forEach(element => {
        let input;
        if (element.getAttribute("type") === "textarea") {
            input = document.createElement("textarea");
            input.setAttribute("style", "width: 100%");
        } else {
            input = document.createElement("input");
            input.setAttribute("type", element.getAttribute("type"));
        }
        input.setAttribute("name", element.getAttribute("name"));
        input.innerHTML = element.innerHTML;
        element.parentNode.replaceChild(input, element);
    });
    let submit = document.createElement("input");
    submit.setAttribute("type", "submit");
    submit.setAttribute("value", "Save");
    form.replaceChild(submit, button);
}