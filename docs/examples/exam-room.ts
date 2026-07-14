import { EdgeMesh, ExamenCompartido, TIPO_PREGUNTA } from "../../src/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { Pregunta } from "../../src/chat/index.js";

async function main() {
  // 1. Initialize teacher node
  const mesh = new EdgeMesh({
    nodoId: "teacher-node" as NodoId,
    peerId: "teacher-id",
  });

  await mesh.iniciar();

  // 2. Create a shared exam
  const examen = new ExamenCompartido("geometry-101", mesh.yjsAdapter);

  // 3. Listen for incoming answers from students
  examen.addEventListener("respuestaNueva", (ev: Event) => {
    const { estudianteId, preguntaId, respuesta } = (ev as CustomEvent).detail;
    console.log(`Student ${estudianteId} submitted answer for ${preguntaId}:`, respuesta);
  });

  // 4. Define and load questions
  const questions: Pregunta[] = [
    {
      id: "q1",
      tipo: TIPO_PREGUNTA.OPCION_MULTIPLE,
      enunciado: "What is the sum of angles in a triangle?",
      opciones: ["90°", "180°", "360°"],
      respuestaCorrecta: "180°",
      puntaje: 1,
    },
    {
      id: "q2",
      tipo: TIPO_PREGUNTA.VERDADERO_FALSO,
      enunciado: "A square is a rectangle.",
      respuestaCorrecta: true,
      puntaje: 1,
    }
  ];

  await examen.cargarPreguntas(questions);

  // 5. Start the exam
  await examen.iniciarExamen();
  console.log("Exam is now live!");
}

main().catch(console.error);
