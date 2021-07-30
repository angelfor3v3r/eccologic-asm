import { h, Component } from "preact";
import { Router } from "preact-router";

import Header from "./header";
import Home   from "./home";

const App = () => (
    <div class="container">
        <Header/>
        <Router>
            <Home path="/"/>
        </Router>
    </div>
);

export default App;