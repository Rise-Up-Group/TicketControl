async function uploadFile(file, fileLink, dropBox) {
    let formData = new FormData();
    let token = RegExp("csrftoken=[^;]+").exec(document.cookie);

    let tokenResponse = await fetch(`/ticket/1/participants/add/`); //TODO
    token = await tokenResponse.text();

    formData.append("csrfmiddlewaretoken", token);
    formData.append("attachment", file);
    let response = await fetch("/attachment/upload", {
        method: "POST",
        body: formData
    });
    if (response.ok) {
        fileLink.style.color = "";
        let id = await response.text()
        fileLink.href = "/attachment/" + id + "/" + file.name;
        let input = document.createElement("input");
        input.type = "hidden";
        input.name = "attachments";
        input.value = id;
        dropBox.appendChild(input)
    }
}

function updateFileDropArea(input) {
    let fileDropList = input.parentNode.parentNode.querySelector("div.file-drop-list");
    let attachments = input.parentNode.parentNode.querySelector(`input[name="attachments"]`);
    for (let file of input.files) {
        let fileLink = document.createElement("a");
        fileLink.innerHTML = file.name + " (size: " + file.size + ")<br>";
        fileLink.style.color = "grey";
        fileDropList.appendChild(fileLink);
        uploadFile(file, fileLink, input.parentNode.parentNode);
    }
    input.value = "";
}