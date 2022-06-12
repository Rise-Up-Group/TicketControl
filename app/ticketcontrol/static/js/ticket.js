async function add_user(mode, username) {
    if (username !== "") {
        let response;
        let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
        let type;
        if (mode === "participants") {
            type = "participant";
            response = await fetch(`{% url 'ticket_add_participant' id=ticket.id %}${username}`, {
                method: "POST",
                headers: {'X-CSRFToken': token}
            });
        } else if (mode === "moderators") {
            type = "moderator";
            response = await fetch(`{% url 'ticket_add_moderator' id=ticket.id %}${username}`, {
                method: "POST",
                headers: {'X-CSRFToken': token}
            });
        }
        if (response.ok) {
            document.getElementById("search-user").value = "";
            let user_list = document.getElementById(mode);
            let user_span = document.createElement("span");
            user_span.setAttribute("id", type+"-"+username);
            if (user_list.childElementCount !== 0) {
                user_span.innerHTML = ", ";
            }
            user_span.innerHTML += username + " [";
            let delete_span = document.createElement("span");
            delete_span.innerHTML = "x";
            delete_span.classList.add("text-danger");
            delete_span.setAttribute("onclick", "delete_"+type+"(`"+username+"`);");
            delete_span.setAttribute("type", "submit");
            user_span.appendChild(delete_span);
            user_span.innerHTML += "]";
            user_list.appendChild(user_span);
        }
    }
}

async function delete_moderator(username) {
    let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
    let id = document.getElementById("ticket-id").innerHTML;
    let response = await fetch("/ticket/"+id+"/moderators/remove/"+username, {
        method: "POST",
        headers: {'X-CSRFToken': token}
    });
    if (response.ok) {
        document.getElementById("moderator-"+username).remove();
    }
}

async function delete_participant(username) {
    let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
    let id = document.getElementById("ticket-id").innerHTML;
    let response = await fetch("/ticket/"+id+"/participants/remove/"+username, {
        method: "POST",
        headers: {'X-CSRFToken': token}
    });
    if (response.ok) {
        document.getElementById("participant-"+username).remove();
    }
}

async function show_update_ticket_warning() {
    document.getElementById("update-ticket-warning").style.display = "";
    let title = document.getElementById("title").value;
    let category = document.getElementById("category").value
    document.getElementById("new_title").value = title;
    document.getElementById("new_category").value = category;
    if (document.getElementById("location")) {
        let location = document.getElementById("location").value;
        document.getElementById("new_location").value = location;
    }
}

async function check_options_dropdown() {
    if (document.getElementById("ticket-options-dropdown").childElementCount === 0) {
        document.getElementById("ticket-options").remove();
    }
}

