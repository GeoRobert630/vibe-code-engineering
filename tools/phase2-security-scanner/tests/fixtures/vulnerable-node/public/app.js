const params = new URLSearchParams(location.search);
document.getElementById("greeting").innerHTML = "Hello " + location.hash.slice(1);
document.write(params.get("banner"));
