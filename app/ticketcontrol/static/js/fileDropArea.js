function updateFileDropArea(input) {
    let fileDropList = input.parentNode.querySelector("div.file-drop-list");
    for (let child of fileDropList.children) {
        child.remove();
    }
    for (let file of input.files) {
        let fileSpan = document.createElement("span");
        fileSpan.innerHTML = file.name + " (size: " + file.size + ")<br>";
        fileDropList.appendChild(fileSpan);
    }
}