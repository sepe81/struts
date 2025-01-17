/*
 * $Id$
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.struts2.showcase.hangman;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class Vocab implements Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	private final String vocab;
	private final String hint;
	private Character[] characters; // character this vocab is made up of

	public Vocab(String vocab, String hint) {
		assert (vocab != null);
		assert (hint != null);

		this.vocab = vocab.toUpperCase();
		this.hint = hint;
	}

	public String getVocab() {
		return this.vocab;
	}

	public String getHint() {
		return this.hint;
	}

	public Boolean containCharacter(Character character) {
		assert (character != null);

		return vocab.contains(character.toString());
	}

	public Character[] inCharacters() {
		if (characters == null) {
			char[] c = vocab.toCharArray();
			characters = new Character[c.length];
			for (int a = 0; a < c.length; a++) {
				characters[a] = c[a];
			}
		}
		return characters;
	}

	public boolean containsAllCharacter(List<Character> charactersGuessed) {
		return new HashSet<>(charactersGuessed).containsAll(Arrays.asList(inCharacters()));
	}

	public static void main(String[] args) throws Exception {
		Vocab v = new Vocab("JAVA", "a java word");

		System.out.println(v.containsAllCharacter(List.of('J', 'V')));
		System.out.println(v.containsAllCharacter(List.of('J', 'V', 'A')));

	}
}
