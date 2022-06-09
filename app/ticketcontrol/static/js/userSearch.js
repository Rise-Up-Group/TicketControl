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