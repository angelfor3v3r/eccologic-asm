import { h, Component }                 from "preact";
import { BrowserRouter, Switch, Route } from "react-router-dom";

import Header   from "./header";
import NotFound from "./not-found"
import Home     from "./home";
import Help     from "./help";

class App extends Component
{
    //on_route_change = e => {
    //
    //};
    // <Router onChange={this.on_route_change}>

    render()
    {
        return(
            <BrowserRouter>
                <Header/>
                <Switch>
                    <Route path="/" component={Home} exact/>
                    <Route path="/help" component={Help}/>
                    <Route component={NotFound}/>
                </Switch>
            </BrowserRouter>
        );
    }
}

export default App;