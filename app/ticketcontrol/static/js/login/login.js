async function submitForm(form) {
    // node list to array
    let inputs = [...form.querySelectorAll("input")]


    let formJSON = inputs
        .filter(e => e.type === "text" || e.type === "password")
        .map(e => `?=${e.name}=${e.value}`)
        .join("");

    // validation missing

    console.log(formJSON)

    let res = await fetch(window.location.pathname, {
        body: formJSON,
        method: "POST",
        headers: new Headers({'content-type': 'ma'}),
    });
}