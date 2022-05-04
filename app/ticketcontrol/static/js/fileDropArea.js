async function uploadAttachment(file, fileLink, dropBox, ticket, comment) {
    let formData = new FormData();
    let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
    formData.append("attachment", file);
    if (typeof ticket !== "undefined") {
        formData.append("ticket", ticket);
    }
    else if (typeof comment !== "undefined") {
        formData.append("comment", comment);
    }

    let response = await fetch("/attachment/upload", {
        method: "POST",
        headers: {'X-CSRFToken': token},
        body: formData
    });

    if (response.ok) {
        let id = await response.text();
        fileLink.style.color = "";
        fileLink.href = "/attachment/" + id + "/name/" + file.name;
        let deleteLink = document.createElement("a");
        deleteLink.innerHTML = "Delete";
        deleteLink.classList.add("text-danger");
        deleteLink.href = "";
        deleteLink.setAttribute("data-toggle", "modal");
        deleteLink.setAttribute("data-target", "#confirm-delete-attachment");
        deleteLink.setAttribute("attachment-id", id);
        deleteLink.setAttribute("file-drop-box-id", dropBox.getAttribute("id"));
        deleteLink.setAttribute("onclick", "selectAttachmentForDelete(this)");
        //deleteLink.addEventListener("click", event => selectAttachmentForDelete(event));
        let div = fileLink.parentNode;
        div.innerHTML += " ";
        div.appendChild(deleteLink);

        let input = document.createElement("input");
        input.type = "hidden";
        input.name = "attachments";
        input.value = id;
        dropBox.appendChild(input)
    }
}

function selectAttachmentForDelete(target) {
    let deleteButton = document.getElementById("confirm-delete-attachment").querySelector(
            `button[name="delete-attachment"]`)
    deleteButton.setAttribute("attachment-id", target.getAttribute("attachment-id"));
    deleteButton.setAttribute("file-drop-box-id", target.getAttribute("file-drop-box-id"))
}

async function deleteAttachment(button) {
    let id = button.getAttribute("attachment-id");
    $("#confirm-delete-attachment").modal("toggle");
    let fileDropBox = document.getElementById(button.getAttribute("file-drop-box-id"))
    let input = fileDropBox.querySelector(`input[name="attachments"][value="`+id+`"]`)
    if (input) input.remove();
    let deleteLink = fileDropBox.querySelector(".file-drop-list").querySelector(`[attachment-id="`+id+`"]`)
    deleteLink.parentNode.remove();

    let token = document.querySelector(`input[name="csrfmiddlewaretoken"]`).value;
    let response = await fetch("/attachment/"+id+"/delete", {
        method: "POST",
        headers: {'X-CSRFToken': token}
    });
}

function updateFileDropArea(input, ticket=undefined, comment=undefined) {
    let fileDropList = input.parentNode.parentNode.querySelector("div.file-drop-list");
    let attachments = input.parentNode.parentNode.querySelector(`input[name="attachments"]`);
    for (let file of input.files) {
        let div = document.createElement("div");
        let fileLink = document.createElement("a");
        fileLink.innerHTML = file.name + " (size: " + file.size + ")";
        fileLink.style.color = "grey";
        div.appendChild(fileLink);
        fileDropList.appendChild(div);
        uploadAttachment(file, fileLink, input.parentNode.parentNode, ticket, comment);
    }
    input.value = "";
}