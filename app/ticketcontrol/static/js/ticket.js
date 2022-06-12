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