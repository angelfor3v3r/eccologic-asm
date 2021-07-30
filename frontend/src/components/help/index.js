import { h } from "preact";

const Home = () => (
    <main>
        <h1>Help page</h1>
        <div class="container">
            <form>
                <div class="form-group">
                    <label for="asm_text_area">Assembly</label>
                    <textarea class="form-control" id="asm_text_area"></textarea>
                </div>
                <button class="btn btn-primary" type="submit">Submit</button>
            </form>
        </div>
    </main>
);

export default Home;