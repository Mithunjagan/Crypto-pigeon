document.getElementById('start-direct').addEventListener('click', async()=>{
  const button=document.getElementById('start-direct'),status=document.getElementById('status');
  button.disabled=true;status.textContent='Starting your private vault…';
  try{await window.pigeonSetup.connect('direct');}
  catch{button.disabled=false;status.textContent='Could not start. Close and reopen Crypto Pigeon.';}
});
document.getElementById('setup').addEventListener('submit', async event => {
  event.preventDefault();
  const button = document.getElementById('connect');
  const status = document.getElementById('status');
  button.disabled = true; status.textContent = 'Checking your relay…';
  try {
    await window.pigeonSetup.connect(document.getElementById('relay').value.trim());
    status.textContent = 'Starting your private vault…';
  } catch {
    status.textContent = 'Could not connect. Enter a working HTTPS relay address without a path, and check your internet connection.';
    button.disabled = false;
  }
});
