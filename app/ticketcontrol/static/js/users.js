async function check_username(autocorrect=true, old_username="") {
    let input = document.getElementById("username");
    let username = input.value;
    if (username !== old_username) {
        let res = await fetch("/user/check_username/" + username, {methd: "GET"});
        if (res.status === 200) {
            input.style.backgroundColor = null;
        } else {
            if (res.status === 409) {
                if (autocorrect) {
                    input.style.backgroundColor = null;
                    username = await res.text();
                    input.value = username;
                } else {
                    input.style.setProperty("background-color", "var(--color-danger)", "important");
                }
            } else {
                input.style.backgroundColor = "red";
            }
        }
    } else {
        input.style.backgroundColor = null;
    }
}

async function search_and_update_usernames(typed_username, id, multiple_enable=true) {
    let seperator = typed_username.lastIndexOf(",");
    let typed, other_usernames = "";
    if (multiple_enable && seperator !== -1) {
        typed = typed_username.substr(seperator+1).trim();
        other_usernames = typed_username.substr(0, seperator+1).trim();
    } else {
        typed = typed_username.trim();
    }
    let users = await (await fetch(`/user/live_search/${typed || "_"}`)).json();
    let dropdown = $("#"+id);
    dropdown.children().remove();
    for (user of users) {
        dropdown.append($(`<option>${other_usernames} ${user.username}</option>`));
    }
}

async function update_username() {
    let first_name = document.getElementById("firstname").value.substring(0, 1);
    let last_name = document.getElementById("lastname").value;
    document.getElementById("username").value = first_name + "." + last_name;
    check_username();
}

function show_custom_username() {
    let checkbox = document.getElementById("custom-username-checkbox");
    if (checkbox.checked) {
        document.getElementById("username").removeAttribute("disabled");
    } else {
        document.getElementById("username").setAttribute("disabled", "");
    }
}