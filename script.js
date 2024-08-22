const carousel = document.querySelector(".carousel")
  

let isDragging = false, startX, scrollLeft;


carousel.addEventListener("mousedown", e => {
  isDragging = true;
  startX = e.pageX;
  scrollLeft = carousel.scrollLeft;
});

carousel.addEventListener("mousemove", e => {
  if (isDragging) carousel.scrollLeft = scrollLeft - (e.pageX - startX) * 2;
});

carousel.addEventListener("mouseup", () => isDragging = false);

const hamburger = document.querySelector('.hamburger');
const nav = document.querySelector('nav ul');

hamburger.addEventListener('click', () => {
  hamburger.classList.toggle('active');
  nav.classList.toggle('active');
});