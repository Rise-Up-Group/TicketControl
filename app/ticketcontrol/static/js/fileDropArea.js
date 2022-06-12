async function upload_attachment(file, file_link, drop_box, ticket, comment) {
    let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
    let form_data = new FormData();
    form_data.append("attachment", file);
    if (typeof ticket !== "undefined") {
        form_data.append("ticket", ticket);
    } else if (typeof comment !== "undefined") {
        form_data.append("comment", comment);
    }

    let response = await fetch("/attachment/upload", {
        method: "POST",
        headers: {'X-CSRFToken': token},
        body: form_data
    });

    if (response.ok) {
        let id = await response.text();
        file_link.style.color = "";
        file_link.href = "/attachment/" + id + "/name/" + file.name;
        let delete_link = document.createElement("a");
        delete_link.innerHTML = "Delete";
        delete_link.classList.add("text-danger");
        delete_link.href = "";
        delete_link.setAttribute("data-toggle", "modal");
        delete_link.setAttribute("data-target", "#confirm-delete-attachment");
        delete_link.setAttribute("attachment-id", id);
        delete_link.setAttribute("file-drop-box-id", drop_box.getAttribute("id"));
        delete_link.setAttribute("onclick", "select_attachment_for_delete(this)");
        let div = file_link.parentNode;
        div.innerHTML += " ";
        div.appendChild(delete_link);

        let input = document.createElement("input");
        input.type = "hidden";
        input.name = "attachments";
        input.value = id;
        drop_box.appendChild(input)
    }
}

function select_attachment_for_delete(target) {
    let delete_button = document.getElementById("confirm-delete-attachment").querySelector(
        `button[name="delete-attachment"]`)
    delete_button.setAttribute("attachment-id", target.getAttribute("attachment-id"));
    delete_button.setAttribute("file-drop-box-id", target.getAttribute("file-drop-box-id"))
}

async function delete_attachment(button) {
    let id = button.getAttribute("attachment-id");
    $("#confirm-delete-attachment").modal("toggle");

    let token = document.querySelector(`input[name="csrfmiddlewaretoken"]`).value;
    let response = await fetch("/attachment/" + id + "/delete", {
        method: "POST",
        headers: {'X-CSRFToken': token}
    });

    if (response.ok) {
        let fileDropBox = document.getElementById(button.getAttribute("file-drop-box-id"))
        let input = fileDropBox.querySelector(`input[name="attachments"][value="` + id + `"]`)
        if (input) input.remove();
        let deleteLink = fileDropBox.querySelector(".file-drop-list").querySelector(`[attachment-id="` + id + `"]`)
        deleteLink.parentNode.remove();
    }
}

async function update_file_drop_area(input, ticket = undefined, comment = undefined) {
    let file_drop_list = input.parentNode.parentNode.querySelector("div.file-drop-list");
    for (let file of input.files) {
        let div = document.createElement("div");
        let file_link = document.createElement("a");
        let size_unit = "B";
        let size = file.size;
        ["KB", "MB", "GB"].forEach(unit => {
            if (size > 2048) {
                size_unit = unit;
                size = parseInt(size / 1024);
            }
        });
        file_link.innerHTML = file.name + " (size: " + size + size_unit + ")";
        file_link.style.color = "grey";
        div.appendChild(file_link);
        file_drop_list.appendChild(div);
        upload_attachment(file, file_link, input.parentNode.parentNode, ticket, comment);
    }
    input.value = "";
}