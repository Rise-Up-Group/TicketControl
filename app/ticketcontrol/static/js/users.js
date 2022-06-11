async function check_username(autocorrect=true) {
    let input = document.getElementById("username");
    let username = input.value;
    let res = await fetch("/user/check_username/"+username, {methd: "GET"});
    if (res.status === 200) {
        input.style.backgroundColor = null;
    } else {
        if (res.status === 409) {
            if (autocorrect) {
                input.style.backgroundColor = null;
                username = await res.text();
                input.value = username;
            } else {
                input.style.backgroundColor = "red";
            }
        } else {
            input.style.backgroundColor = "red";
        }
    }
}

async function search_and_update_usernames(typed_username, id, multipleEnable=true) {
    let seperator = typed_username.lastIndexOf(",");
    let typed, otherUsernames = "";
    if (multipleEnable && seperator !== -1) {
        typed = typed_username.substr(seperator+1).trim();
        otherUsernames = typed_username.substr(0, seperator+1).trim();
    } else {
        typed = typed_username.trim();
    }
    let users = await (await fetch(`/user/live_search/${typed || "_"}`)).json();
    let dropdown = $("#"+id);
    dropdown.children().remove();
    for (user of users) {
        dropdown.append($(`<option>${otherUsernames} ${user.username}</option>`));
    }
}

async function update_username() {
    let firstname = document.getElementById("firstname").value.substring(0, 1);
    let lastname = document.getElementById("lastname").value;
    document.getElementById("username").value = firstname + "." + lastname;
    check_username();
}

function showCustomUsername() {
    let checkbox = document.getElementById("checkCustomUsername");
    if (checkbox.checked) {
        document.getElementById("username").removeAttribute("disabled");
    } else {
        document.getElementById("username").setAttribute("disabled", "");
    }
}