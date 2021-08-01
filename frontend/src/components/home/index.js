import { h, Component } from "preact";

class Home extends Component
{
    constructor()
    {
        super();
        this.state = { asm_text: "", asm_mode: "", asm_arch: "" };
    }

    // TODO: Handle each "onChange" event for the text/mode/arch
    //

    //async encode()
    //{
    //    const resp = await fetch( window.location.origin + "/api/encode",
    //    {
    //        method: "POST",
    //        headers: {
    //            "Accept": "application/json",
    //            "Content-Type": "application/json"
    //        },
    //        body: ""
    //    });
    //
    //    return await resp.json();
    //}

    on_change = e =>
    {
        // this.setState( { asm_text: e.target.value } );
    }

    on_submit = e =>
    {
        console.log( JSON.stringify( this.state ) );

        //encode().then( ( res ) => {
        //    console.log( "res: " + res );
        //})
        //.catch( ( err ) => {
        //    console.log( "error: " + err );
        //});

        e.preventDefault();
    };

    render( _, { asm_text } )
    {
        return(
            <main>
                <h1>Home page</h1>
                <div class="container">
                    <form onSubmit={this.on_submit}>
                        <div class="mb-3">
                            <label for="asm_text_area" class="form-label">Assembly</label>
                            <textarea class="form-control" id="asm_text_area" rows="6"></textarea>
                        </div>
                        <div class="row g-2 align-items-center">
                            <div class="col-auto">
                                <div class="form-floating">
                                    <select class="form-select" id="asm_mode">
                                        <option selected>Encode</option>
                                        <option>Decode</option>
                                    </select>
                                    <label for="asm_mode">Mode</label>
                                </div>
                            </div>
                            <div class="col-auto">
                                <div class="form-floating">
                                    <select class="form-select" id="asm_arch">
                                        <option selected>x86-64</option>
                                        <option>x86-32</option>
                                        <option>x86-16</option>
                                        <option>AArch64</option>
                                    </select>
                                    <label for="asm_arch">Architecture</label>
                                </div>
                            </div>
                            <div class="col-auto">
                                <button class="btn btn-primary" type="submit">Submit</button>
                            </div>
                        </div>
                    </form>
                </div>
            </main>);
    }
}

export default Home;