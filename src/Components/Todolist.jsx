import { useState, useEffect } from "react";
import api from './Api';
import "./todolist.css";
const Todolist = () => {
    const [item, setItem] = useState('');
    const [itemlist, setItemlist] = useState([]);
    const [checkedItems, setcheckedItems] = useState([]);
    const [editItemId, setEditItemId] = useState(null);
    const [editedItemText, setEditedItemText] = useState(''); 
    const [completedItems, setCompletedItems] = useState([]);
    const [setButtonVisible] = useState(true);

    const [showTodoList, setShowTodoList] = useState(false); 
    const [showCompletedTasks, setShowCompletedTasks] = useState(false);
   
   //USE EFFECT fetching
    useEffect(() => {
        fetchItemlist();
        fetchCompletedList();
    }, []); 
    

    //Handling the checkbox
    const handleCheckboxChange = (id) => {
        setcheckedItems(prev => {
            const index = prev.indexOf(id);
            if (index > -1) {
                return [...prev.slice(0, index), ...prev.slice(index + 1)];
            } else {
                return [...prev, id];
            }
        });
    };


    
    //handling the new item input
    const handleinput = (e) => {
        setItem(e.target.value);
    };


    

    //Adding list
    const addItem = async (e) => {
        e.preventDefault();

        if (item.trim() !== '') {
            await api.post('/TodoList/', { newItem: item });
            fetchItemlist();
            setItem('');
        }
    }




  //Fetching list from database
    const fetchItemlist = async () => {
        try {
            const response = await api.get('/TodoList/');
            setItemlist(response.data);
        } catch (error) {
            console.error("Error fetching item list: ", error);
        }
    }


//delete item
    const deleteItem = async (id) => {
        try {
            await api.delete(`/TodoList/${id}`);
            fetchItemlist();
        } catch (error) {
            console.error("Error deleting item: ", error);
        }
    };

//clear all todolist

const clearItems = async () =>{
    try{
        await api.delete('/TodoList/');
        fetchItemlist();
    } catch (error){
        console.error("Error Clearing The todolist items")
    }
    setButtonVisible(false)
};


//editing todolist function
    const editItem = (id, text) => {
        setEditItemId(id);
        setEditedItemText(text); 
    };


//Saving editeditem functionality
    const saveEditedItem = async (id, editedText) => {
        try {
            await api.put(`/TodoList/${id}`, { newItem: editedText });
            setEditItemId(null); 
            fetchItemlist();
        } catch (error) {
            console.error("Error saving edited item: ", error);
        }
    };


    //Completed task functionality

    const markAsCompleted = async (id) => {
        try {
            await api.post('/CompletedList/', { completedItem: itemlist.find(item => item.id === id).newItem });
            // Update completedItems state
            setCompletedItems(prev => [...prev, { id, completedItem: itemlist.find(item => item.id === id).newItem }]);
            // Remove completed item from itemlist state
            setItemlist(prev => prev.filter(item => item.id !== id));
            // Update checkedItems state to remove completed item
            setcheckedItems(prev => prev.filter(item => item !== id));
        } catch (error) {
            console.error("Error marking item as completed: ", error);
        }
    };
    


    

//Fetching completedtask from 'completedlist' table in the database
    const fetchCompletedList = async () => {
        try {
            const response = await api.get('/CompletedList/');
            setCompletedItems(response.data);
        } catch (error) {
            console.error("Error fetching completed item list: ", error);
        }
    }
    

//Clear completed list
    const clearCompletedList = async () =>{
        try{
            await api.delete('/CompletedList/');
            fetchCompletedList();
        } catch (error){
            console.error("Error Clearing The CompletedList items")
        }
        setButtonVisible(false);
    };
    
   
    return (
        <>

       <div className="todo_cont">
       <h1> TODO APP</h1>




       

       </div>
       
        <div className="main_container">

      
            <form>
                <label htmlFor="label">New Task</label>
                <input className="inputs" value={item} onChange={handleinput} type="text" placeholder="Track Your Todos"/>
                <button className="btn" onClick={addItem}>Add</button>
            </form>

            <div className="nav_buttons">
                <button className="todolist_btn" onClick={() => { setShowTodoList(true); setShowCompletedTasks(false); }}>View Todolist</button>
                <button className="completed_btn" onClick={() => { setShowTodoList(false); setShowCompletedTasks(true); }}>View Completed</button>
            </div>

            {showTodoList && (
                <div className="todolist">
                    <h2>Todo list</h2>
                    <div className="todoitems">  
                    <ul>
                        {itemlist.length === 0 ?(
                            <h3> Your Todo lists will appear here</h3>
                        ):
                        itemlist.map((item) => (
                            <div key={item.id}>
                                <input type="checkbox" checked={checkedItems.includes(item.id)} onChange={() => handleCheckboxChange(item.id)}  /> 
                                {editItemId === item.id && checkedItems.includes(item.id) ? (
                                    <>
                                        <input
                                            type="text"
                                            value={editedItemText}
                                            onChange={(e) => setEditedItemText(e.target.value)} 
                                            onBlur={() => saveEditedItem(item.id, editedItemText)} 
                                        />
                                        <button onClick={() => saveEditedItem(item.id, editedItemText)}>Save</button> 
                                    </>
                                ) : (
                                    <>
                                        <span>{item.newItem}</span>
                                        
                                        {checkedItems.includes(item.id) && <button className="item_button" onClick={() => editItem(item.id, item.newItem)}>Edit</button>}
                                    </>
                                )}
                                {checkedItems.includes(item.id) && <button className="item_button" onClick={() => markAsCompleted(item.id)}>Mark as Completed</button>}
                                {checkedItems.includes(item.id) && <button className="item_button"  onClick={() => deleteItem(item.id)}>Delete</button>}
                            </div>
                        ))}
                    </ul>
                    </div>
                  
                    {itemlist.length > 0  && (
                        <button className="clear_item_btn" onClick={clearItems}>Clear All</button>
                    )}
                    
                </div>
            )}

            {showCompletedTasks && (
                <div className="completed-tasks">
                    <h2>Completed Tasks</h2>
                    {completedItems.length === 0 ? (
                        <h3>You have not completed any tasks</h3>
                    ) : (
                        completedItems.map((item) => (
                            <div className="completed_list" key={item.id}>
                                <input checked type="checkbox" placeholder="checked" /> {item.completedItem}
                            </div>
                        ))
                    )}
                    {completedItems.length > 0 && (
                        <button className="clear_btn" onClick={clearCompletedList}>Clear All</button>
                    )}
                </div>
            )}

            </div>

        
         <section className="attribute_section">
         <footer className="attribution">
            Created by <br></br>

                <a href="https://github.com/abasiman?tab=repositories" >
                Abas Iman
                </a>
            </footer>

         </section>


     
            


        </>
    );
}

export default Todolist;
