document.getElementById('registerForm').addEventListener('submit', async (e) => {

    e.preventDefault();

    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    const response = await fetch('/register', {

        method:'POST',

        headers:{
            'Content-Type':'application/json'
        },

        body:JSON.stringify({
            username,
            password
        })

    });

    alert(await response.text());

});

document.getElementById('loginForm').addEventListener('submit', async (e) => {

    e.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    const response = await fetch('/login',{

        method:'POST',

        headers:{
            'Content-Type':'application/json'
        },

        body:JSON.stringify({
            username,
            password
        })

    });

    alert(await response.text());

});