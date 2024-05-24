import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';


import LoginPopup from "./Components/LoginPopup.jsx";

import Todolist from "./Components/Todolist.jsx";


const App = () => {
  return (
    <Router>
        <Routes>
            <Route path="/" element={<LoginPopup />} />
            <Route path="/Todolist" element={<Todolist />} />
        </Routes>
    </Router>
);
};

export default App;
