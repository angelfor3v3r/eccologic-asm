import { h, Component, Fragment } from "preact";
import { Router }                 from "preact-router";

import Header from "./header";
import Home   from "./home";
import Help   from "./help";

class App extends Component
{
    //on_route_change = e => {
    //
    //};
    // <Router onChange={this.on_route_change}>

    render()
    {
        return(
            <>
                <Header/>
                <Router>
                    <Home path="/"/>
                    <Help path="/help"/>
                    <Home default/>
                </Router>
            </>);
    }
}

export default App;