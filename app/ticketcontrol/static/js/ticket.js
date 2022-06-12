async function add_user(mode, username) {
    if (username !== "") {
        let response;
        let token = document.querySelector('[name=csrfmiddlewaretoken]').value;
        if (mode === "participants") {
            response = await fetch(`{% url 'ticket_add_participant' id=ticket.id %}${username}`, {
                method: "POST",
                headers: {'X-CSRFToken': token}
            });
        } else if (mode === "moderators") {
            response = await fetch(`{% url 'ticket_add_moderator' id=ticket.id %}${username}`, {
                method: "POST",
                headers: {'X-CSRFToken': token}
            });
        }
        if (response.ok) {
            document.getElementById("search-user").value = "";
            let user_list = document.getElementById(mode);
            let user_list_html = user_list.innerHTML.trim();
            if (typeof user_list_html === "undefined" || user_list_html === "") {
                user_list.innerHTML = user_list_html + username;
            } else {
                user_list.innerHTML = user_list_html + ", " + username;
            }
        }
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
