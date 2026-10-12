# @swal/edge-mesh-react

React bindings for [Edge Mesh](https://github.com/iberi22/edge-mesh) (`@swal/edge-mesh`):
a `Provider` plus the `useEdgeMesh` and `useCollection` hooks for shared
Yjs collections (Map or Array) synced over the owner-controlled P2P mesh.

> Unpublished companion package (v1.0.0, `private`). License: [Apache-2.0](../..).

## Install

```bash
npm install @swal/edge-mesh yjs react
```

`@swal/edge-mesh` (`^0.1.1`) and `react` (`>=18.0.0`) are peer dependencies;
`yjs` is the CRDT layer. ESM only (`import`), no CommonJS build.

## Usage

Wrap your tree in the provider with a running `EdgeMesh` instance, then read
and mutate a shared collection from any nested component.

```tsx
import { EdgeMesh } from "@swal/edge-mesh";
import { EdgeMeshProvider, useCollection } from "@swal/edge-mesh-react";

const mesh = new EdgeMesh({ nodoId: "device-a", storageBackend: "mem" });
await mesh.iniciar();

export function App() {
  return (
    <EdgeMeshProvider edgeMesh={mesh}>
      <TodoList />
    </EdgeMeshProvider>
  );
}

function TodoList() {
  const [todos, { add, remove, update }] = useCollection("todos", { type: "map" });

  return (
    <ul>
      {todos.map((todo) => (
        <li key={todo.id}>
          {todo.text}
          <button onClick={() => remove(todo.id)}>done</button>
        </li>
      ))}
      <button onClick={() => add({ id: crypto.randomUUID(), text: "New todo", done: false })}>
        add
      </button>
    </ul>
  );
}
```

### API

- `EdgeMeshProvider` (`Provider` alias) — props: `{ edgeMesh: EdgeMesh; children }`.
  Makes the mesh instance available via context.
- `useEdgeMesh()` — returns the `EdgeMesh` instance; throws when used outside
  the provider.
- `useCollection<T>(name, { type })` — subscribes to the shared Yjs `Map`
  (default) or `Array` called `name` and re-renders on remote updates.
  Returns `[items, helpers]` where helpers are
  `{ collection, add, remove, update, set, get }`.
