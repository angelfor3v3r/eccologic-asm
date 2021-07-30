import { h } from "preact";

const Home = () => (
    <main>
        <h1>Home page</h1>
        <div class="container">
            <form>
                <div class="mb-3">
                    <label for="asm_text_area" class="form-label">Assembly</label>
                    <textarea class="form-control" id="asm_text_area" rows="6"></textarea>
                </div>
                <div class="mb-2">
                    <label for="asm_mode">Mode</label>
                    <select class="form-control" id="asm_mode">
                        <option>Encode</option>
                        <option>Decode</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label for="asm_arch">Architecture</label>
                    <select class="form-control" id="asm_arch">
                        <option>x86-64</option>
                        <option>x86-32</option>
                        <option>x86-16</option>
                    </select>
                </div>
                <button class="btn btn-primary" type="submit">Submit</button>
            </form>
        </div>
    </main>
);

export default Home;