//var counter =1;
function add_todo(){
    var x= document.getElementById("task").value
    const node =document.createElement('div')
    node.className ="list-group-item list-group-item-danger list-group-numbered mb-2"
    node.style.textAlign = "left";
   //const tnode = document.createTextNode(counter + ". " );
   // node.appendChild(tnode);
   // counter++;
    
    
    var checkbox = document.createElement('input');
    checkbox.type = "checkbox";
    checkbox.className = "form-check-input";
    checkbox.style.float= "right";
    const textnode =document.createTextNode(x)


    
    node.appendChild(textnode)
    node.appendChild(checkbox);
    checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
            node.style.backgroundColor = "lightblue";
            alert("task compelete")
            document.getElementById("ee").remove()
            
             //node.appendChild(completedText);
             var completedText = document.createElement('div');
             var c= document.createElement('textnode') 
            
           c.textContent ="Task completed"
            c.style ="float:right;margin-right: 7px; margin-top:5px;"
    

             completedText.className = "text-center mt-10";
             completedText.textContent = "Task Completed";
             completedText.style.textAlign="right"
             node.appendChild(c);


        } else {
            node.style.backgroundColor = ""; // Reset to default color
        }
    });
    
   


    
    
    var b= document.createElement('button') 
    b.className ="btn btn-danger"
    b.textContent ="Delete"
    b.style ="float:right; "
    node.appendChild(b)
    b.onclick=delete_todo
    var c= document.createElement('button') 
    c.className ="btn btn-warning"
    c.textContent ="Edit"
    c.style ="float:right;margin-right: 5px;"
    c.id ="ee"
    c.onclick=edit_todo 
    node.appendChild(c)
     
    document.getElementById("result").appendChild(node)
    document.getElementById("task").value=" "
   

}
function clear_todo(){
    document.getElementById("result").innerHTML=""
}
function delete_todo(e){
    e.target.parentElement.remove()

}
function edit_todo(e){
    const newdiv =document.createElement('div')
    newdiv.className ="Container text-center mt-3"
    var i = document.createElement('input')
    i.className ="form-control"
    i.setAttribute("type","text")
    newdiv.appendChild(i)
    var b1= document.createElement('button') 
    b1.className ="btn btn-success"
    b1.textContent ="update"
    b1.onclick = edit_text
    newdiv.appendChild(b1)
    
    e.target.parentElement.appendChild(newdiv)
    var b2= document.createElement('button') 
    b2.className ="btn btn-danger"
    b2.textContent ="close"
    b2.onclick = close_box
    newdiv.appendChild(b2)

}
function edit_text(e){
    y= e.target.parentElement.firstChild.value
    const textnode1 =document.createTextNode(y)
    e.target.parentElement.parentElement.replaceChild(textnode1,e.target.parentElement.parentElement.firstChild )
    e.target.parentElement.remove()

}
function close_box(e){
    e.target.parentElement.remove()
}
